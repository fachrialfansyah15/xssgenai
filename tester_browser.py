from __future__ import annotations

import logging

from playwright.sync_api import Error as PWError, sync_playwright

from utils import (
    _acquire_page,
    _release_page,
    init_browser_pool,
    pool_available,
)
from tester_ui import console

logger = logging.getLogger("xsscanner.tester")

_PLAYWRIGHT_AVAILABLE = True
_PLAYWRIGHT_FAILURE_REASON = ""
_PLAYWRIGHT_NOTIFIED = False

PLAYWRIGHT_EXEC_INIT_SCRIPT = """\
(() => {
  const mark = () => { window.__xss_executed = true; };
  window.__xss_executed = false;
  ['alert','confirm','prompt','print'].forEach(fn=>{
    try{
      const o = window[fn];
      Object.defineProperty(window, fn, { value: function(...a){ mark(); try{return o.apply(this,a)}catch(e){} }} );
    }catch(e){}
  });
  const _onerror = window.onerror;
  window.onerror = function(){ mark(); if (typeof _onerror==='function') { try{ _onerror.apply(this, arguments) }catch(e){} } };
  document.addEventListener('securitypolicyviolation', () => {});
})();
"""


def _simulate_user_interactions(page) -> None:
    """Broadened user-like interactions to trigger event-driven payloads."""
    try:
        try:
            page.hover("body")
        except PWError:
            pass
        for sel in ["[autofocus]", "input, textarea, select, [contenteditable]"]:
            try:
                for el in page.query_selector_all(sel):
                    try:
                        if el.is_visible():
                            el.focus()
                            page.wait_for_timeout(80)
                    except PWError:
                        continue
            except PWError:
                continue
        for sel in ["[onmouseover]", "[onmouseenter]", "[onmouseleave]"]:
            try:
                for el in page.query_selector_all(sel):
                    try:
                        if el.is_visible():
                            el.hover()
                            page.wait_for_timeout(60)
                    except PWError:
                        continue
            except PWError:
                continue
        for sel in ["button", "a", "[role=button]", "[onclick]", "[onfocus]", "[onload]"]:
            try:
                for el in page.query_selector_all(sel):
                    try:
                        if el.is_visible() and el.is_enabled():
                            el.click(timeout=1000, no_wait_after=True)
                            page.wait_for_timeout(80)
                    except PWError:
                        continue
            except PWError:
                continue
        try:
            page.keyboard.press("Enter")
        except PWError:
            pass
        try:
            page.keyboard.press("Space")
        except PWError:
            pass
    except Exception:
        pass


def confirm_execution(url: str, timeout_ms: int = 20000) -> bool:
    """
    Buka URL di Playwright, override alert/prompt/confirm/print + onerror,
    simulasikan interaksi ringan, dan return True jika terlihat indikasi eksekusi.
    """
    global _PLAYWRIGHT_AVAILABLE, _PLAYWRIGHT_FAILURE_REASON, _PLAYWRIGHT_NOTIFIED
    if not _PLAYWRIGHT_AVAILABLE:
        return False

    hit = {"flag": False}

    try:
        if pool_available() or init_browser_pool():
            ctx, page = _acquire_page()
            if ctx and page:
                try:
                    def _on_dialog(d):
                        try:
                            hit["flag"] = True
                            d.dismiss()
                        except PWError:
                            pass
                    page.on("dialog", _on_dialog)
                    page.add_init_script(
                        """
                        (() => {
                          const mark = () => { window.__xss_executed = true; };
                          window.__xss_executed = false;
                          ['alert','confirm','prompt','print'].forEach(fn=>{
                            try{
                              const o = window[fn];
                              Object.defineProperty(window, fn, { value: function(...a){ mark(); try{return o.apply(this,a)}catch(e){} }} );
                            }catch(e){}
                          });
                          const _onerror = window.onerror;
                          window.onerror = function(){ if (typeof _onerror==='function') { try{ _onerror.apply(this, arguments) }catch(e){} } };
                          document.addEventListener('securitypolicyviolation', () => {});
                        })();
                        """
                    )
                    try:
                        page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                    except PWError:
                        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)

                    try:
                        _simulate_user_interactions(page)
                    except Exception:
                        pass

                    try:
                        page.hover("body")
                    except PWError:
                        pass
                    for sel in ["button", "a[href]", "[onclick]", "input[type=submit]", "img[onerror]"]:
                        try:
                            for el in page.query_selector_all(sel):
                                try:
                                    if el.is_visible() and el.is_enabled():
                                        el.click(timeout=1000, no_wait_after=True)
                                        page.wait_for_timeout(120)
                                except PWError:
                                    continue
                        except PWError:
                            continue
                    for _ in range(4):
                        try:
                            page.keyboard.press("Tab")
                            page.wait_for_timeout(80)
                        except PWError:
                            break
                    try:
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(180)
                        page.evaluate("window.scrollTo(0, 0)")
                        page.wait_for_timeout(120)
                    except PWError:
                        pass
                    try:
                        page.evaluate(
                            """
                            () => {
                              const evs = [
                                'click','dblclick','mouseover','mouseout','mouseenter','mouseleave','contextmenu',
                                'focus','blur','input','change','submit','keydown','keyup','wheel',
                                'animationiteration','animationstart','animationend','transitionend'
                              ];
                              document.querySelectorAll('*').forEach(el => {
                                evs.forEach(name => { try { el.dispatchEvent(new Event(name, {bubbles:true,cancelable:true})) } catch(e) {} });
                              });
                            }
                            """
                        )
                        page.wait_for_timeout(200)
                    except PWError:
                        pass
                    exec_flag = False
                    try:
                        exec_flag = bool(page.evaluate("() => !!window.__xss_executed"))
                    except PWError:
                        exec_flag = False
                    return bool(hit["flag"] or exec_flag)
                finally:
                    try:
                        _release_page(ctx, page)
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(java_script_enabled=True)

            def _on_dialog(d):
                try:
                    hit["flag"] = True
                    d.dismiss()
                except PWError:
                    pass

            page = context.new_page()
            page.on("dialog", _on_dialog)
            page.add_init_script(
                """
                (() => {
                  const mark = () => { window.__xss_executed = true; };
                  window.__xss_executed = false;
                  ['alert','confirm','prompt','print'].forEach(fn=>{
                    try{
                      const o = window[fn];
                      Object.defineProperty(window, fn, { value: function(...a){ mark(); try{return o.apply(this,a)}catch(e){} }} );
                    }catch(e){}
                  });
                  const _onerror = window.onerror;
                  window.onerror = function(){ if (typeof _onerror==='function') { try{ _onerror.apply(this, arguments) }catch(e){} } };
                  document.addEventListener('securitypolicyviolation', () => {});
                })();
                """
            )
            try:
                try:
                    page.goto(url, wait_until="networkidle", timeout=timeout_ms)
                except PWError:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                try:
                    _simulate_user_interactions(page)
                except Exception:
                    pass
                try:
                    page.hover("body")
                except PWError:
                    pass
                for sel in ["button", "a[href]", "[onclick]", "input[type=submit]", "img[onerror]"]:
                    try:
                        for el in page.query_selector_all(sel):
                            try:
                                if el.is_visible() and el.is_enabled():
                                    el.click(timeout=1000, no_wait_after=True)
                                    page.wait_for_timeout(120)
                            except PWError:
                                continue
                    except PWError:
                        continue
                for _ in range(4):
                    try:
                        page.keyboard.press("Tab")
                        page.wait_for_timeout(80)
                    except PWError:
                        break
                try:
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    page.wait_for_timeout(180)
                    page.evaluate("window.scrollTo(0, 0)")
                    page.wait_for_timeout(120)
                except PWError:
                    pass
                try:
                    page.evaluate(
                        """
                        () => {
                          const evs = [
                            'click','dblclick','mouseover','mouseout','mouseenter','mouseleave','contextmenu',
                            'focus','blur','input','change','submit','keydown','keyup','wheel',
                            'animationiteration','animationstart','animationend','transitionend'
                          ];
                          document.querySelectorAll('*').forEach(el => {
                            evs.forEach(name => { try { el.dispatchEvent(new Event(name, {bubbles:true,cancelable:true})) } catch(e) {} });
                          });
                        }
                        """
                    )
                    page.wait_for_timeout(200)
                except PWError:
                    pass
                exec_flag = False
                try:
                    exec_flag = bool(page.evaluate("() => !!window.__xss_executed"))
                except PWError:
                    exec_flag = False
                return bool(hit["flag"] or exec_flag)
            finally:
                try:
                    page.close()
                    context.close()
                    browser.close()
                except Exception:
                    pass
    except (PWError, FileNotFoundError, OSError) as exc:
        _PLAYWRIGHT_AVAILABLE = False
        _PLAYWRIGHT_FAILURE_REASON = str(exc)
        logger.warning("Playwright runtime tidak siap: %s", exc)
        if not _PLAYWRIGHT_NOTIFIED:
            console.print(
                "[yellow]Analisis runtime dilewati karena Playwright browser belum terpasang. "
                "Jalankan `playwright install` lalu ulangi untuk mengaktifkan verifikasi otomatis.[/yellow]"
            )
            _PLAYWRIGHT_NOTIFIED = True
        return False

    return False


def is_playwright_available() -> bool:
    return _PLAYWRIGHT_AVAILABLE


__all__ = ["confirm_execution", "is_playwright_available", "PLAYWRIGHT_EXEC_INIT_SCRIPT"]
