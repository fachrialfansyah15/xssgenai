# tester.py - ULTRA-MAX (drop-in replacement, Playwright-only)
from __future__ import annotations

import copy
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from csrf import apply_csrf
from dynamic_dom_tester import dynamic_dom_inspect
from network import make_request
from payload_strategy import SuperBypassEngine
from parsers.xss_classifier import classify_categories, summarize_categories
from resilience import compute_resilience_score, run_resilience_browser_probe
from sanitization_analyzer import analyze_param_sanitizer, mutate_payload_by_sanitizer, pretty_print_map
from tester_analysis import (
    get_xss_severity,
    sink_location_labels as _sink_location_labels,
    summarize_filter_profile,
)
from tester_phases import XSSTesterPhasesMixin
from tester_ui import (
    Panel,
    color,
    console,
    configure_ui,
    format_eta as _fmt_eta,
    preview_payload as _preview_payload,
    print_progress as _print_progress,
    progress_newline as _progress_newline,
    short_url as _short_url,
)


logger = logging.getLogger("xsscanner.tester")


class XSSTester(XSSTesterPhasesMixin):
    def __init__(self, payloads: dict, max_workers: int = 10, progress_every: int = 25, verbose: bool = True, sanitizer_detail: str = "summary", hash_fuzz: bool = True, waf_plan: dict | None = None, skip_encoding: bool = False):
        self.payloads = payloads
        self.engine = SuperBypassEngine(payloads)
        try:
            if waf_plan:
                self.engine.set_waf_plan(waf_plan)
        except Exception:
            pass
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self.vulns: List[Dict] = []
        self.progress_every = max(1, int(progress_every))
        self.verbose = bool(verbose)
        self.sanitizer_detail = (sanitizer_detail or "summary").strip().lower()
        # Scheduler untuk revisit (stored/time-delayed)
        self.revisit_tasks: List[Dict] = []
        self.hash_fuzz = bool(hash_fuzz)
        self.skip_encoding = bool(skip_encoding)
        self._last_runtime_findings: List[Dict] = []
        self.ai_snapshots: Dict[tuple, Dict[str, Any]] = {}
        self._active_ai_key: Optional[tuple] = None
        self.resilience_reports: List[Dict] = []
        self._resilience_cache: Dict[str, Dict[str, Any]] = {}
        self._filter_profile_flags: Dict[str, bool] = {}
        self._current_filter_profile: Dict[str, Any] = {}

    @property
    def last_runtime_findings(self) -> List[Dict]:
        """Return a shallow copy of the most recent runtime findings."""
        return list(self._last_runtime_findings or [])

    def set_filter_profile(self, profile: Dict[str, Any] | None) -> None:
        """Store sanitizer-derived filter flags and propagate to the engine."""
        if profile is None:
            prof: Dict[str, Any] = {}
        elif isinstance(profile, dict):
            try:
                prof = copy.deepcopy(profile)
            except Exception:
                prof = dict(profile)
        else:
            prof = {}

        try:
            flags = dict((prof.get("flags") or {}))
        except Exception:
            flags = {}

        self._current_filter_profile = prof
        self._filter_profile_flags = flags

        try:
            self.engine.set_filter_profile(flags)
        except Exception:
            pass

        try:
            key = self._active_ai_key
            if key and key in self.ai_snapshots:
                snap = copy.deepcopy(self.ai_snapshots[key])
                snap["filter_profile"] = prof
                snap["filter_profile_flags"] = flags
                self._save_ai_snapshot(key, snap)
        except Exception:
            pass

    def _save_ai_snapshot(self, key: tuple, data: Dict[str, Any]) -> None:
        try:
            self.ai_snapshots[key] = copy.deepcopy(data)
        except Exception:
            try:
                self.ai_snapshots[key] = dict(data)
            except Exception:
                self.ai_snapshots[key] = {}

    def _annotate_ai_outcome(self, finding: Dict[str, Any], executed: bool) -> None:
        try:
            key = self._active_ai_key
            snap = self.ai_snapshots.get(key) if key else None
            if not snap:
                pname = finding.get('param')
                if pname:
                    for k, v in self.ai_snapshots.items():
                        if v.get('name') == pname:
                            snap = v
                            key = k
                            break
            if not snap or not key:
                return
            update = copy.deepcopy(snap)
            score = float(update.get('ai_score', 0) or 0)
            score += 90 if executed else 35
            update['ai_score'] = score
            update['phase'] = 'vuln_executed' if executed else 'vuln_detected'
            vulns = update.setdefault('vulns', [])
            summary = {
                'url': finding.get('url'),
                'param': finding.get('param'),
                'type': finding.get('type'),
                'class': finding.get('class'),
                'payload': finding.get('payload'),
            }
            vulns.append(summary)
            self._save_ai_snapshot(key, update)
        except Exception:
            pass

    def _classify(self, finding: Dict, executed: bool = False, runtime: List[Dict] | None = None) -> Dict:
        try:
            runtime = runtime if runtime is not None else self._last_runtime_findings
        except Exception:
            runtime = None
        if executed:
            finding.setdefault('class', 'Executed')
            finding.setdefault('confidence', 'high')
            self._annotate_ai_outcome(finding, executed=True)
            return finding
        t = (finding.get('type') or '').lower()
        if 'blind' in t or 'stored' in t:
            finding.setdefault('class', 'Stored/Blind')
            finding.setdefault('confidence', 'high')
            self._annotate_ai_outcome(finding, executed=False)
            return finding
        try:
            if runtime:
                # Sandbox hint first
                if any((rf.get('type') or '').lower() == 'sandbox_iframe' for rf in runtime):
                    finding.setdefault('class', 'Blocked-by-Sandbox')
                    finding.setdefault('confidence', 'info')
                    return finding
                # CSP signals
                if any((rf.get('type') or '').lower() == 'csp_violation' for rf in runtime):
                    finding.setdefault('class', 'Blocked-by-CSP')
                    finding.setdefault('confidence', 'info')
                    return finding
                for rf in runtime:
                    if (rf.get('type') or '') == 'csp_flags':
                        import json as _json
                        detail = rf.get('detail') or ''
                        try:
                            obj = _json.loads(detail)
                            flags = (obj or {}).get('flags') or {}
                            if flags.get('no_inline_script'):
                                finding.setdefault('class', 'Blocked-by-CSP')
                                finding.setdefault('confidence', 'info')
                                return finding
                        except Exception:
                            pass
        except Exception:
            pass
        finding.setdefault('class', 'DOM-sink-only')
        finding.setdefault('confidence', 'medium')
        self._annotate_ai_outcome(finding, executed=False)
        return finding

    def resilience_summary(self) -> Dict[str, Any]:
        return compute_resilience_score(self.resilience_reports, has_vulns=bool(self.vulns))

    def build_findings_report(self) -> List[Dict[str, Any]]:
        """Aggregate discovered vulns into a concise report with sinks and effects."""
        report: List[Dict[str, Any]] = []

        def _snap_for(param: str) -> Dict[str, Any] | None:
            snap = None
            try:
                for k, v in self.ai_snapshots.items():
                    if (v or {}).get("name") == param:
                        snap = v
                return snap
            except Exception:
                return None

        for v in list(self.vulns or []):
            try:
                param = v.get("param") or v.get("parameter") or "-"
                snap = _snap_for(param)
                contexts = (snap or {}).get("contexts") or v.get("contexts") or []
                sinks = v.get("sinks") or _sink_location_labels(contexts)
                classification = (snap or {}).get("classification") or {}
                cats = summarize_categories(classification) if classification else []
                runtime = (snap or {}).get("runtime_findings") or []
                filter_profile = (snap or {}).get("filter_profile") or {}
                vclass = (v.get("class") or "").lower()
                if vclass == "executed":
                    kind = None
                    try:
                        for rf in runtime:
                            t = (rf.get('type') or '').lower()
                            if t.startswith('dialog_'):
                                kind = t.replace('dialog_', '')
                                break
                    except Exception:
                        pass
                    effect = f"Dialog executed ({kind})" if kind else "Dialog/Execution observed"
                elif (v.get("type") or "").startswith("blind-xss"):
                    effect = "Blind XSS beacon received"
                elif (v.get("type") or "").startswith("stored"):
                    effect = "Stored/delayed reflection observed"
                else:
                    if any((rf.get('type') or '').lower() in ("csp_violation", "trustedtypes_policy") for rf in runtime):
                        effect = "Blocked (CSP/TrustedTypes)"
                    elif any((rf.get('type') or '').lower() == "sandbox_iframe" for rf in runtime):
                        effect = "Blocked (sandbox iframe)"
                    else:
                        effect = "Reflected, no runtime execution"

                report.append({
                    "param": param,
                    "url": v.get("url") or v.get("origin_url") or "-",
                    "payload": v.get("payload") or v.get("base_payload") or "-",
                    "type": v.get("type") or "-",
                    "class": v.get("class") or "-",
                    "sinks": sinks or [],
                    "categories": cats or [],
                    "effect": effect,
                    "filter": filter_profile,
                })
            except Exception:
                continue
        return report

    def generate_recommendations(self) -> Dict[str, List[str]]:
        """Produce remediation recommendations based on observed contexts and resilience probe."""
        rec: Dict[str, List[str]] = {
            "input_output": [],
            "dom_api": [],
            "csp": [],
            "headers": [],
            "framework": [],
        }

        ctx: set[str] = set()
        try:
            for snap in (self.ai_snapshots or {}).values():
                for c in (snap or {}).get("contexts", []) or []:
                    ctx.add(str(c))
        except Exception:
            pass
        try:
            rt = self._contexts_from_runtime(self._last_runtime_findings or [])
            for c in rt:
                ctx.add(str(c))
        except Exception:
            pass

        has_attr = any(x in ctx for x in ("attr_quoted", "attr_unquoted", "data_attribute", "srcdoc_attr"))
        has_html = any(x in ctx for x in ("html_tag", "polyglot", "script_tag"))
        has_js = any(x in ctx for x in ("js_string", "template_literal"))
        has_css = any(x in ctx for x in ("css_url", "css_expression"))
        has_uri = any(x in ctx for x in ("uri_scheme", "uri_javascript"))
        has_event = any(x.startswith("on") or x == "event_handler" for x in ctx)

        if has_html:
            rec["input_output"].append("Apply HTML-escape on text content (escape <, >, &, \\\" , ').")
            rec["input_output"].append("Prefer server/template auto-escaping for body text.")
        if has_attr:
            rec["input_output"].append("Encode attribute values (quote, ampersand) and enforce quoting.")
            rec["input_output"].append("Validate attribute names; never reflect untrusted on* attributes.")
        if has_js:
            rec["input_output"].append("Do not concatenate untrusted data into JS strings; use JSON.stringify and data-bound props.")
            rec["input_output"].append("Prefer textContent over innerHTML; avoid eval/Function/setTimeout with string.")
        if has_uri:
            rec["input_output"].append("Allowlist URL schemes (http:, https:, mailto) and reject/strip javascript:, data:, vbscript:.")
            rec["input_output"].append("Use URL parsing APIs and percent-encode untrusted segments.")
        if has_css:
            rec["input_output"].append("Avoid injecting untrusted data into style/cssText; disallow url() and expression().")

        rec["dom_api"].append("Avoid dangerous sinks: innerHTML/outerHTML/document.write/insertAdjacentHTML.")
        if has_event:
            rec["dom_api"].append("Remove inline event handlers; use addEventListener in JS modules.")
        rec["dom_api"].append("Sanitize any required HTML with a robust library (e.g., DOMPurify) on an allowlist basis.")

        csp_seen = []
        tt_seen = []
        try:
            for rep in (self.resilience_reports or []):
                csp = (rep.get('resilience_probe') or {}).get('csp') or {}
                flags = csp.get('flags') or {}
                if flags:
                    csp_seen.append(flags)
                tt = (rep.get('resilience_probe') or {}).get('trusted_types') or {}
                if tt:
                    tt_seen.append(tt)
        except Exception:
            pass

        if csp_seen:
            rec["csp"].append("Tighten Content-Security-Policy based on observed flags (script-src, object-src, base-uri).")
        if tt_seen:
            rec["csp"].append("Consider Trusted Types enforcement (require-trusted-types-for 'script').")
        if not csp_seen and not tt_seen:
            rec["csp"].append("No CSP/trusted types evidence observed; consider adding CSP with nonce-based script policy.")

        rec["headers"].append("Ensure X-XSS-Protection disabled (modern browsers rely on CSP).")
        rec["headers"].append("Review Referrer-Policy, Permissions-Policy, and frame-ancestors if reflecting into framing contexts.")

        rec["framework"].append("Enable framework auto-escaping features (e.g., React JSX, Angular, Django templates).")
        rec["framework"].append("Validate templating helpers: avoid raw HTML rendering unless sanitized.")

        return rec

    def schedule_revisit(self, url: str, marker: str, delay_seconds: int = 300, note: str = "") -> None:
        try:
            due = time.time() + max(1, int(delay_seconds))
            self.revisit_tasks.append({"url": url, "marker": marker, "due": due, "note": note})
            if self.verbose:
                logger.info(f"[revisit] scheduled {url} in {delay_seconds}s")
        except Exception:
            pass

    def process_revisits(self, max_items: int = 5) -> None:
        now = time.time()
        ready = [t for t in self.revisit_tasks if t.get("due", 0) <= now]
        ready = sorted(ready, key=lambda x: x.get("due", 0))[:max_items]
        for task in ready:
            url = task.get("url")
            marker = task.get("marker")
            _progress_newline()
            console.print(color(f"[Revisit] {url} (marker={marker})", "cyan"))
            try:
                findings = dynamic_dom_inspect(url)
            except Exception:
                findings = []
            text = "\n".join([str(f) for f in findings])
            if (marker or "") and (marker in text):
                console.print(Panel(f"URL: {url}\nMarker: {marker}", title="[green]Stored/Delayed XSS Indication[/green]"))
                f = {"url": url, "param": "<stored>", "payload": marker, "type": "stored_delayed"}
                self.vulns.append(self._classify(f))
            try:
                self.revisit_tasks.remove(task)
            except Exception:
                pass


    def test_parameter(
        self,
        url: str,
        method: str,
        name: str,
        template: Dict[str, str],
        is_form: bool,
        sanitizer_baseline: Optional[Dict[str, str]] | None = None,
        request_meta: Optional[Dict[str, Any]] = None,
    ):
        method = method.upper()
        console.print(f"[Start] Testing param='{name}' method={method} url={url}")

        initial_vulns = len(self.vulns)

        key = (url, method, name)
        entry: Dict[str, Any] = {
            "url": url,
            "origin_url": url,
            "name": name,
            "method": method,
            "is_form": bool(is_form),
            "template": copy.deepcopy(template),
            "data_template": copy.deepcopy(template),
        }
        if self._current_filter_profile:
            try:
                entry["filter_profile"] = copy.deepcopy(self._current_filter_profile)
            except Exception:
                entry["filter_profile"] = dict(self._current_filter_profile)
            entry["filter_profile_flags"] = dict(self._filter_profile_flags)
        if request_meta:
            try:
                entry["request_meta"] = copy.deepcopy(request_meta)
            except Exception:
                entry["request_meta"] = dict(request_meta)
        self._active_ai_key = key
        self._save_ai_snapshot(key, entry)

        # 1) Analisis sanitizer (karakter apa yg filtered/encoded/reflected)
        sanitizer_map = (
            dict(sanitizer_baseline)
            if sanitizer_baseline is not None
            else analyze_param_sanitizer(url, name, template, method, is_form, request_meta=request_meta)
        )
        timeout_chars = [ch for ch, status in (sanitizer_map or {}).items() if status == "timeout"]
        if timeout_chars:
            entry["sanitizer_timeouts"] = timeout_chars
            for ch in timeout_chars:
                sanitizer_map[ch] = "filtered"
        if not self._current_filter_profile:
            try:
                auto_profile = summarize_filter_profile(sanitizer_map, mangling=None)
            except Exception:
                auto_profile = {}
            if isinstance(auto_profile, dict) and auto_profile:
                self.set_filter_profile(auto_profile)
                try:
                    entry["filter_profile"] = copy.deepcopy(self._current_filter_profile)
                except Exception:
                    entry["filter_profile"] = dict(self._current_filter_profile)
                entry["filter_profile_flags"] = dict(self._filter_profile_flags)
        # Ringkas: tampilkan ringkasan status; detail hanya saat verbose
        try:
            from collections import Counter
            cnt = Counter(sanitizer_map.values())
        except Exception:
            cnt = {"filtered": 0, "encoded": 0, "reflected": 0}
            for st in sanitizer_map.values():
                cnt[st] = cnt.get(st, 0) + 1

        filtered_total = int(cnt.get("filtered", 0) or 0)
        encoded_total = int(cnt.get("encoded", 0) or 0)
        reflected_total = int(cnt.get("reflected", 0) or 0)

        entry["sanitizer_map"] = sanitizer_map
        entry["sanitizer_summary"] = {
            "filtered": filtered_total,
            "encoded": encoded_total,
            "reflected": reflected_total,
        }
        entry["sanitizer_map_full"] = sanitizer_map
        entry["ai_score"] = reflected_total - filtered_total
        entry["phase"] = "sanitizer"
        self._save_ai_snapshot(key, entry)

        # Selalu tampilkan ringkasan ringkas
        _print_progress(f"[sanitizer] {name}: filtered={filtered_total}, encoded={encoded_total}, reflected={reflected_total}")
        # Detail hanya bila diminta secara eksplisit
        if self.sanitizer_detail == "full":
            _progress_newline()
            pretty_print_map(name, sanitizer_map)

        # 2) Phase headers untuk UX yang lebih jelas
        _progress_newline()
        console.print(color("[Phase 2] Encoding variants…", "cyan"))

        # 2) Encoding variants (prioritas simple, cepat, dan sering lolos)
        if self._phase_encoding_plus(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "encoding_plus_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 3] Quick probes: OOB, Header, Path/Fragment, Stored…", "cyan"))
        _print_progress("[oob] sent, waiting events…")
        # 3) Blind-XSS OOB (tidak blocking; SSE/polling akan menghentikan saat hit)
        if self._phase_oob(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "oob_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        # Path/Fragment mengelola progress internal
        # 3.7) Path/Fragment injection probing (ringan)
        if self._phase_path_fragment(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "path_fragment_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        # Header reflection mengelola progress internal
        # 3.6) Header reflection probing (ringan)
        if self._phase_header_reflection(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "header_reflection_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _print_progress("[stored] probing…")
        # 3.5) Stored-XSS probing (ringan)
        if self._phase_stored(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "stored_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 4] CSP-aware & nonce/hash bypass…", "cyan"))
        _print_progress("[csp] trying payloads…")
        # 4) CSP-aware & nonce/hash bypass (jika terlihat CSP)
        if self._phase_csp(url, method, name, template, is_form, request_meta=request_meta):
            entry["phase"] = "csp_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 5] Probe → Progressive (engine)…", "cyan"))
        _print_progress("[probe] checking reflection…")
        # 5) Probe â†’ Progressive (context-aware via engine)
        probe = f"XSSPROBE{int(time.time())}"
        if self._phase_probe_progressive(url, method, name, template, is_form, probe, request_meta=request_meta):
            entry["phase"] = "probe_progressive_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 6] Coverage-guided (CDP)…", "cyan"))
        _print_progress("[coverage] scoring candidates…")
        # 6) Coverage-guided (gunakan CDP precise coverage dari dynamic_dom_tester)
        raw_html = self._get_rendered_html(url, method, name, template, is_form, probe, request_meta=request_meta)
        if self._phase_coverage(url, method, name, template, is_form, raw_html, probe, request_meta=request_meta):
            entry["phase"] = "coverage_success"
            self._save_ai_snapshot(key, entry)
            self._active_ai_key = None
            return

        _progress_newline()
        console.print(color("[Phase 7] Static context-aware brute (parallel)…", "cyan"))
        _print_progress("[static] running parallel payloads…")
        # 7) Static context-aware brute (paralel, aware sanitizer)
        contexts = self._detect_contexts(raw_html, probe)
        try:
            runtime_findings = dynamic_dom_inspect(url, hash_fuzz=self.hash_fuzz)
        except Exception:
            runtime_findings = []
        self._last_runtime_findings = runtime_findings or []
        rt_ctx = self._contexts_from_runtime(runtime_findings)
        if rt_ctx:
            contexts = list(dict.fromkeys(list(contexts) + list(rt_ctx)))
        entry["contexts"] = contexts
        entry["runtime_findings"] = runtime_findings or []
        entry["phase"] = "static_pre"
        self._save_ai_snapshot(key, entry)
        self._run_static_tests(url, method, name, template, is_form, contexts, sanitizer_map, request_meta=request_meta)
        entry["phase"] = "completed"
        self._save_ai_snapshot(key, entry)
        if len(self.vulns) == initial_vulns:
            probe = self._resilience_cache.get(url)
            if probe is None:
                try:
                    probe = run_resilience_browser_probe(url)
                except Exception as exc:
                    probe = {"error": str(exc)}
                self._resilience_cache[url] = probe
            self.resilience_reports.append({
                "url": url,
                "param": name,
                "method": method,
                "sanitizer_summary": entry.get("sanitizer_summary", {}),
                "sanitizer_map": entry.get("sanitizer_map_full", {}),
                "runtime_findings": runtime_findings or [],
                "contexts": contexts,
                "resilience_probe": probe,
            })
        _progress_newline()
        self._active_ai_key = None
