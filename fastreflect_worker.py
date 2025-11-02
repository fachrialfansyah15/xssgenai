from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Optional, Union


class FastReflectWorker:
    """Persistent helper process for fast decode/contains operations."""

    def __init__(self, exe_path: Union[str, os.PathLike[str]]) -> None:
        exe = Path(exe_path)
        if not exe.exists():
            raise FileNotFoundError(exe)
        self._proc = subprocess.Popen(
            [str(exe)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if self._proc.stdin is None or self._proc.stdout is None:
            raise RuntimeError("failed to open pipes to fastreflect process")
        self._stdin = self._proc.stdin
        self._stdout = self._proc.stdout
        self._lock = threading.Lock()
        self._counter = 0

    def close(self) -> None:
        with self._lock:
            try:
                if self._stdin:
                    try:
                        self._stdin.close()
                    except Exception:
                        pass
                if self._stdout:
                    try:
                        self._stdout.close()
                    except Exception:
                        pass
                if self._proc and self._proc.poll() is None:
                    try:
                        self._proc.terminate()
                    except Exception:
                        pass
                    try:
                        self._proc.wait(timeout=1)
                    except Exception:
                        pass
            finally:
                self._stdin = None
                self._stdout = None
                self._proc = None

    def _request(self, payload: dict) -> dict:
        with self._lock:
            if self._stdin is None or self._stdout is None:
                raise RuntimeError("fastreflect worker is closed")
            self._counter += 1
            payload.setdefault("id", self._counter)
            data = json.dumps(payload, separators=(",", ":"))
            self._stdin.write(data + "\n")
            self._stdin.flush()
            line = self._stdout.readline()
        if not line:
            raise RuntimeError("fastreflect worker closed pipe")
        resp = json.loads(line)
        if resp.get("error"):
            raise RuntimeError(resp["error"])
        return resp

    def decode(self, text: str) -> str:
        resp = self._request({"op": "decode", "text": text or ""})
        result = resp.get("result")
        return result if isinstance(result, str) else ""

    def contains(self, haystack: str, needle: str) -> bool:
        resp = self._request({"op": "contains", "haystack": haystack or "", "needle": needle or ""})
        return bool(resp.get("result"))


_worker: Optional[FastReflectWorker] = None
_init_failed = False
_init_lock = threading.Lock()


def get_worker() -> Optional[FastReflectWorker]:
    global _worker, _init_failed
    if _worker is not None:
        return _worker
    if _init_failed:
        return None
    with _init_lock:
        if _worker is not None:
            return _worker
        if _init_failed:
            return None
        exe = _guess_executable_path()
        if not exe:
            _init_failed = True
            return None
        try:
            _worker = FastReflectWorker(exe)
        except Exception:
            _init_failed = True
            _worker = None
        return _worker


def _guess_executable_path() -> Optional[Path]:
    base = Path(__file__).resolve().parent
    candidates = [
        base / "tools" / "fastreflect" / "fastreflect.exe",
        base / "tools" / "fastreflect" / "fastreflect",
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def shutdown() -> None:
    global _worker
    if _worker is not None:
        _worker.close()
        _worker = None
