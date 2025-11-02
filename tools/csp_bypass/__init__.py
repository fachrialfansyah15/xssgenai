from __future__ import annotations

import csv
import logging
import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Sequence

logger = logging.getLogger("xsscanner.csp_bypass")

DATA_PATH = Path(__file__).with_name("data.tsv")
IGNORED_KEYWORDS = {
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'none'",
    "'strict-dynamic'",
    "'report-sample'",
}
MAX_MATCHES = 12


@lru_cache(maxsize=1)
def _load_dataset() -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    if not DATA_PATH.exists():
        logger.debug("CSP bypass dataset not found at %s", DATA_PATH)
        return entries

    try:
        with DATA_PATH.open(encoding="utf-8") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            for row in reader:
                domain = (row.get("Domain") or row.get("domain") or "").strip()
                code = (row.get("Code") or row.get("code") or "").strip()
                if not domain or not code:
                    continue
                entries.append(
                    {
                        "domain": domain,
                        "domain_lower": domain.lower(),
                        "code": code,
                    }
                )
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Failed to load CSP bypass dataset: %s", exc)
        return []
    return entries


def _normalize_source(source: str) -> Optional[str]:
    token = (source or "").strip()
    if not token:
        return None

    low = token.lower()
    if low in IGNORED_KEYWORDS:
        return None
    if low.startswith("'nonce-") or low.startswith("'sha"):
        return None

    # Remove surrounding quotes
    token = token.strip("\"'")
    low = token.lower()

    if not low or low in IGNORED_KEYWORDS:
        return None
    if low.startswith("nonce-") or low.startswith("sha"):
        return None
    if low.startswith(("data:", "blob:", "mediastream:")):
        return None

    # Strip schemes and leading slashes
    low = re.sub(r"^(?:https?|wss?|ftp):", "", low)
    low = low.lstrip("/")
    if low.startswith("//"):
        low = low[2:]

    host = low.split("/")[0]
    host = host.split("?")[0]
    if host.startswith("["):
        host = host.strip("[]")
    if ":" in host:
        host = host.split(":")[0]

    host = host.replace("*", "")
    host = host.lstrip(".")

    if not host or "." not in host:
        return None
    return host


def _sources_to_hosts(sources: Sequence[str]) -> List[str]:
    hosts: List[str] = []
    for src in sources or []:
        norm = _normalize_source(src)
        if norm:
            hosts.append(norm)
    # Remove duplicates but keep order
    return list(dict.fromkeys(hosts))


def _domain_matches(entry_domain: str, host: str) -> bool:
    if entry_domain == host:
        return True
    if entry_domain.endswith("." + host):
        return True
    if host.endswith("." + entry_domain):
        return True
    return False


def collect_csp_bypass_payloads(
    sources: Sequence[str], limit: int = MAX_MATCHES
) -> List[str]:
    dataset = _load_dataset()
    if not dataset:
        return []

    hosts = _sources_to_hosts(sources)
    if not hosts:
        return []

    matches: List[str] = []
    for entry in dataset:
        domain = entry["domain_lower"]
        for host in hosts:
            if _domain_matches(domain, host.lower()):
                matches.append(entry["code"])
                break
        if limit and len(matches) >= limit:
            break

    if matches:
        logger.debug(
            "Matched %d CSP bypass payload(s) for hosts: %s",
            len(matches),
            hosts,
        )
    return matches
