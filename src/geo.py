from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from parser import VlessNode


def apply_ipinfo_countries(
    nodes: list[VlessNode], token: str, cache_path: Path
) -> tuple[int, int, int]:
    now = datetime.now(timezone.utc)
    try:
        saved = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        saved = {}
    if not isinstance(saved, dict):
        saved = {}

    cache: dict[str, dict[str, str]] = {}
    for ip, record in saved.items():
        if not isinstance(ip, str) or not isinstance(record, dict):
            continue
        country = record.get("country")
        checked_at = record.get("checked_at")
        if not isinstance(country, str) or len(country) != 2 or not isinstance(checked_at, str):
            continue
        try:
            checked = datetime.fromisoformat(checked_at)
        except ValueError:
            continue
        if checked.tzinfo is not None and now - timedelta(days=30) <= checked <= now:
            cache[ip] = record

    for node in nodes:
        record = cache.get(node.exit_ip or "")
        if record:
            node.country = record["country"]

    ips = sorted({node.exit_ip for node in nodes if node.exit_ip})
    missing = [ip for ip in ips if ip not in cache]
    for offset in range(0, len(missing), 1000):
        batch = missing[offset : offset + 1000]
        request = Request(
            f"https://api.ipinfo.io/batch/lite?token={quote(token, safe='')}",
            data=json.dumps(batch).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("IPinfo returned an unexpected response")
        for ip in batch:
            record = result.get(ip)
            country = record.get("country_code") if isinstance(record, dict) else None
            if isinstance(country, str) and len(country) == 2:
                cache[ip] = {"country": country.upper(), "checked_at": now.isoformat()}

    classified = 0
    for node in nodes:
        record = cache.get(node.exit_ip or "")
        if record:
            node.country = record["country"]
            classified += 1

    if cache != saved:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return classified, len(ips) - len(missing), len(missing)
