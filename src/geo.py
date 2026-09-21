from __future__ import annotations

import ipaddress
import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

from parser import VlessNode


def lookup_ip_countries(
    ips: set[str], token: str, cache_path: Path
) -> tuple[dict[str, str], int, int]:
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

    missing = [ip for ip in sorted(ips) if ip not in cache]
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

    if cache != saved:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {ip: cache[ip]["country"] for ip in ips if ip in cache}, len(ips) - len(missing), len(missing)


def apply_ipinfo_countries(
    nodes: list[VlessNode], token: str, cache_path: Path
) -> tuple[int, int, int]:
    countries, cached, queried = lookup_ip_countries(
        {node.exit_ip for node in nodes if node.exit_ip}, token, cache_path
    )
    classified = 0
    for node in nodes:
        country = countries.get(node.exit_ip or "")
        if country:
            node.country = country
            classified += 1
    return classified, cached, queried


def resolve_host_ips(nodes: list[VlessNode]) -> tuple[dict[str, str], int]:
    def resolve(host: str) -> str | None:
        try:
            address = ipaddress.ip_address(host)
            return str(address) if address.is_global else None
        except ValueError:
            pass
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                answers = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
            except (OSError, UnicodeError, ValueError):
                continue
            for answer in answers:
                try:
                    address = ipaddress.ip_address(answer[4][0])
                except ValueError:
                    continue
                if address.is_global:
                    return str(address)
        return None

    hosts = {node.host for node in nodes}
    resolved: dict[str, str] = {}
    completed = 0
    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(resolve, host): host for host in hosts}
        for future in as_completed(futures):
            ip = future.result()
            if ip:
                resolved[futures[future]] = ip
            completed += 1
            if completed % 500 == 0 or completed == len(hosts):
                print(f"Geo DNS: {completed}/{len(hosts)}, resolved={len(resolved)}", flush=True)
    return resolved, len(hosts) - len(resolved)
