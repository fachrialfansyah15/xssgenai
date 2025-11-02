from __future__ import annotations

import re
import threading
import time
from typing import Any

try:
    from rich.panel import Panel as _RichPanel  # type: ignore
    from rich.console import Console as _RichConsole  # type: ignore
except Exception:  # pragma: no cover - rich optional
    _RichPanel = None
    _RichConsole = None

_RICH_CONSOLE = None
_PROGRESS_STYLE = "spinner"
_LAST_PROGRESS_MSG = ""
_PROGRESS_PAD = 120
_PROGRESS_ACTIVE = False
_PROGRESS_MSG = ""
_SPINNER_THREAD: threading.Thread | None = None
_SPINNER_STOP: threading.Event | None = None
_SPINNER_FRAMES = ["|", "/", "-", "\\"]

_COL = {
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "bold": "1",
}
_ANSI_ENABLED = True  # CLI already enables Windows ANSI; safe to assume here


class _DummyStatus:
    def __init__(self, msg: str):
        self.msg = msg

    def __enter__(self):
        if not _RICH_CONSOLE and self.msg:
            print(self.msg)
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class _SimpleConsole:
    def print(self, *args: Any, **kwargs: Any) -> None:
        if _RICH_CONSOLE is not None:
            _RICH_CONSOLE.print(*args, **kwargs)
        else:
            print(*args)

    def status(self, message: str, spinner: str = "dots"):
        if _RICH_CONSOLE is not None:
            return _RICH_CONSOLE.status(message, spinner=spinner)
        return _DummyStatus(message)


def Panel(content: Any, title: str | None = None, border_style: str | None = None):
    if _RICH_CONSOLE is not None and _RichPanel is not None:
        safe_border = border_style or ""
        return _RichPanel(content, title=title, border_style=safe_border)
    header = f"=== {title} ===\n" if title else ""
    return f"{header}{content}"


console = _SimpleConsole()


def color(text: str, name: str | None = None) -> str:
    if not name:
        return text
    code = _COL.get(name)
    if not code:
        return text
    return f"\033[{code}m{text}\033[0m"


def _spinner_loop() -> None:
    global _PROGRESS_ACTIVE
    i = 0
    while _SPINNER_STOP and not _SPINNER_STOP.is_set():
        frame = _SPINNER_FRAMES[i % len(_SPINNER_FRAMES)]
        i += 1
        try:
            line = (_PROGRESS_MSG or "").strip()
            if len(line) > _PROGRESS_PAD - 4:
                line = line[: _PROGRESS_PAD - 7] + "..."
            visible = f"{line} {frame}"
            pad = max(0, _PROGRESS_PAD - len(visible))
            color_name = _progress_color_for_message(line)
            out = color(visible, color_name) + (" " * pad)
            print("\r" + out, end="", flush=True)
            _PROGRESS_ACTIVE = True
        except Exception:
            pass
        time.sleep(0.1)


def _ensure_spinner_running() -> None:
    global _SPINNER_THREAD, _SPINNER_STOP
    if _SPINNER_THREAD and _SPINNER_THREAD.is_alive():
        return
    _SPINNER_STOP = threading.Event()
    _SPINNER_THREAD = threading.Thread(target=_spinner_loop, daemon=True)
    _SPINNER_THREAD.start()


def _progress_color_for_message(msg: str) -> str | None:
    try:
        if " EXEC" in msg:
            return "green"
        if " REFL" in msg:
            return "yellow"
        match = re.search(r"hits=(\d+)", msg)
        if match and int(match.group(1)) == 0:
            return "red"
        if "Success" in msg or "Executed" in msg or "Execution" in msg:
            return "green"
    except Exception:
        pass
    return None


def print_progress(msg: str) -> None:
    """Emit progress update respecting configured UI style."""
    global _PROGRESS_MSG, _LAST_PROGRESS_MSG
    clean = (msg or "").strip()
    if _PROGRESS_STYLE != "spinner":
        if not clean or clean == _LAST_PROGRESS_MSG:
            return
        _LAST_PROGRESS_MSG = clean
        color_name = _progress_color_for_message(clean) or "cyan"
        if _RICH_CONSOLE is not None:
            _RICH_CONSOLE.print(f"[{color_name}]{clean}[/{color_name}]")
        else:
            print(color(clean, color_name))
        return
    _PROGRESS_MSG = clean
    _ensure_spinner_running()


def progress_newline() -> None:
    global _PROGRESS_ACTIVE
    global _SPINNER_THREAD, _SPINNER_STOP
    if _PROGRESS_STYLE != "spinner":
        return
    if _SPINNER_STOP:
        _SPINNER_STOP.set()
    if _SPINNER_THREAD:
        try:
            _SPINNER_THREAD.join(timeout=0.5)
        except Exception:
            pass
    _SPINNER_THREAD = None
    _SPINNER_STOP = None
    if _PROGRESS_ACTIVE:
        print()
        _PROGRESS_ACTIVE = False


def configure_ui(*, console=None, progress_style: str | None = None) -> None:
    """Configure tester output UI integration (rich console, progress style)."""
    global _RICH_CONSOLE, _PROGRESS_STYLE, _LAST_PROGRESS_MSG
    if console is not None:
        _RICH_CONSOLE = console
    if progress_style:
        normalized = str(progress_style).lower()
        if normalized not in {"spinner", "log"}:
            normalized = "spinner"
        if normalized != _PROGRESS_STYLE and _PROGRESS_STYLE == "spinner":
            progress_newline()
        _PROGRESS_STYLE = normalized
        _LAST_PROGRESS_MSG = ""


def preview_payload(s: str, limit: int = 120) -> str:
    try:
        if not s:
            return "-"
        s = str(s).replace("\n", "\\n").replace("\r", "").strip()
        if len(s) > limit:
            return s[: limit - 3] + "..."
        return s
    except Exception:
        return "-"


def short_url(u: str, limit: int = 60) -> str:
    try:
        if not u:
            return "-"
        from urllib.parse import urlsplit

        parts = urlsplit(u)
        base = f"{parts.scheme}://{parts.netloc}{parts.path or ''}"
        if len(base) > limit:
            return base[: limit - 3] + "..."
        return base
    except Exception:
        return u[:limit]


def format_eta(total: int, done: int, start_ts: float) -> str:
    try:
        if done <= 0:
            return "--:--"
        elapsed = max(0.0, time.time() - start_ts)
        rate = done / elapsed if elapsed > 0 else 0
        if rate <= 0:
            return "--:--"
        remain = max(0.0, (total - done) / rate)
        mm = int(remain // 60)
        ss = int(remain % 60)
        return f"{mm:02d}:{ss:02d}"
    except Exception:
        return "--:--"


__all__ = [
    "Panel",
    "color",
    "console",
    "configure_ui",
    "format_eta",
    "preview_payload",
    "print_progress",
    "progress_newline",
    "short_url",
]
