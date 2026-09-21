from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from dedupe import canonical_key, deduplicate
from fetch import fetch_all
from geo import apply_ipinfo_countries, lookup_ip_countries, resolve_host_ips
from parser import VlessNode, is_secure, parse_source
from ranking import group_by_country, rank
from singbox import check_nodes_via_singbox, measure_speeds
from tester import check_nodes


ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"
OUTPUT_DIR = ROOT / "output"
CACHE_FILE = OUTPUT_DIR / "ip-country-cache.json"
HISTORY_FILE = ROOT / "history.json"
TOP_N = 10
SPEED_CANDIDATES_PER_COUNTRY = 20
SPEED_TEST_LIMIT = 60
TARGET_COUNTRIES = {
    "AZ", "BY", "DE", "EE", "FI", "GE", "KZ", "LT", "LV", "NL", "NO", "PL", "SE", "TR",
}


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def node_key(node: VlessNode) -> str:
    value = "\x1f".join(canonical_key(node)).encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def write_nodes(path: Path, nodes: list[VlessNode]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [node.uri for node in nodes]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_labeled_nodes(path: Path, nodes: list[VlessNode]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    country_counts: dict[str, int] = {}
    for node in nodes:
        country = node.country.upper()
        country_counts[country] = country_counts.get(country, 0) + 1
        flag = ""
        if len(country) == 2 and country.isascii() and country.isalpha() and country != "ZZ":
            flag = "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in country)
        label = (
            f"{flag} {country} #{country_counts[country]:02d} | "
            f"{node.speed_mbps:.1f} Mbps | {node.latency_ms:.0f} ms"
        ).strip()
        lines.append(f"{node.uri.partition('#')[0]}#{quote(label, safe='')}")
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def write_country_subscription(path: Path, nodes: list[VlessNode], run_at: str, title: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.fromisoformat(run_at).astimezone(timezone(timedelta(hours=3)))
    updated = timestamp.strftime("%d.%m.%Y %H:%M МСК")
    lines = [
        f"#profile-title: {title}",
        f"#sub-info-text: Обновлено: {updated} | Конфигов: {len(nodes)} | Страна по IP-адресу; доступность не проверялась",
        "#profile-update-interval: 2",
        "#subscriptions-sort-type: without",
    ]
    country_counts: dict[str, int] = {}
    for node in nodes:
        country = node.country
        country_counts[country] = country_counts.get(country, 0) + 1
        flag = "".join(chr(0x1F1E6 + ord(letter) - ord("A")) for letter in country)
        label = f"{flag} {country} #{country_counts[country]:03d}"
        lines.append(f"{node.uri.partition('#')[0]}#{quote(label, safe='')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_country_only(
    nodes: list[VlessNode], source_stats: dict[str, dict[str, Any]], fetched: list[Any], run_at: str
) -> int:
    token = os.environ.get("IPINFO_TOKEN")
    if not token:
        raise ValueError("IPINFO_TOKEN is required for country-only mode")
    if not any(not result.error for result in fetched):
        raise RuntimeError("No source was fetched; subscription was not replaced")

    host_ips, unresolved_hosts = resolve_host_ips(nodes)
    countries, cached_ips, queried_ips = lookup_ip_countries(set(host_ips.values()), token, CACHE_FILE)
    for node in nodes:
        node.country = countries.get(host_ips.get(node.host, ""), "ZZ")
    selected = sorted(
        (node for node in nodes if node.country in TARGET_COUNTRIES),
        key=lambda node: (node.country, node.host, node.port, node.uuid),
    )
    if not selected:
        raise RuntimeError("No nodes matched the selected countries; subscription was not replaced")
    groups = group_by_country(selected)
    timestamp = datetime.fromisoformat(run_at).astimezone(timezone(timedelta(hours=3)))
    title = f"VLESS рядом {timestamp:%d.%m %H:%M}"

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_country_subscription(OUTPUT_DIR / "best.txt", selected, run_at, title)
    countries_dir = OUTPUT_DIR / "countries"
    countries_dir.mkdir(exist_ok=True)
    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for country, country_nodes in sorted(groups.items()):
        write_country_subscription(
            countries_dir / f"{country}.txt", country_nodes, run_at, f"VLESS {country} {timestamp:%d.%m %H:%M}"
        )
    for legacy_name in ("all-working.txt", "tcp-open.txt"):
        legacy_path = OUTPUT_DIR / legacy_name
        if legacy_path.is_file():
            legacy_path.unlink()

    stats = {
        "generated_at": run_at,
        "country_mode": "server_address_ipinfo",
        "availability_checked": False,
        "security_filter": "disabled",
        "target_countries": sorted(TARGET_COUNTRIES),
        "country_counts": {country: len(country_nodes) for country, country_nodes in sorted(groups.items())},
        "fetched_sources": sum(1 for result in fetched if not result.error),
        "failed_sources": sum(1 for result in fetched if result.error),
        "sources": source_stats,
        "parsed_nodes": sum(info.get("parsed", 0) for info in source_stats.values()),
        "unique_nodes": len(nodes),
        "resolved_hosts": len(host_ips),
        "unresolved_hosts": unresolved_hosts,
        "geoip_cached_ips": cached_ips,
        "geoip_queried_ips": queried_ips,
        "selected_nodes": len(selected),
    }
    write_json(OUTPUT_DIR / "stats.json", stats)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def update_history(nodes: list[VlessNode], verified_nodes: list[VlessNode], run_at: str) -> None:
    history = read_json(HISTORY_FILE, {"runs": 0, "nodes": {}})
    history.setdefault("nodes", {})
    history["runs"] = int(history.get("runs", 0)) + 1
    history["last_run"] = run_at
    for node in nodes:
        key = node_key(node)
        record = history["nodes"].setdefault(key, {"runs": 0})
        record["runs"] = int(record.get("runs", 0)) + 1
        record["last_seen"] = run_at
    for node in verified_nodes:
        record = history["nodes"][node_key(node)]
        recent = record.get("recent_verified_runs", [])
        record["recent_verified_runs"] = [
            run for run in recent if isinstance(run, int) and run > history["runs"] - 5
        ] + [history["runs"]]
    write_json(HISTORY_FILE, history)


def build(args: argparse.Namespace) -> int:
    run_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    if args.country_only and not os.environ.get("IPINFO_TOKEN"):
        raise ValueError("IPINFO_TOKEN is required for country-only mode")
    sources = read_json(SOURCES_FILE, [])
    if not isinstance(sources, list):
        raise ValueError("sources.json must contain a list")

    fetched = fetch_all(sources)
    all_nodes: list[VlessNode] = []
    source_stats: dict[str, dict[str, Any]] = {}
    for result in fetched:
        if result.error:
            print(f"WARN {result.name}: {result.error}", file=sys.stderr)
            source_stats[result.name] = {"url": result.url, "error": result.error}
            continue
        parsed = parse_source(result.text, result.name)
        if not args.include_insecure and not args.country_only:
            parsed = [node for node in parsed if is_secure(node)]
        all_nodes.extend(parsed)
        source_stats[result.name] = {
            "url": result.url,
            "parsed": len(parsed),
        }

    unique_nodes = deduplicate(all_nodes)
    print(
        f"Fetched: sources={len(fetched)}, parsed={len(all_nodes)}, unique={len(unique_nodes)}",
        flush=True,
    )
    if args.country_only:
        return build_country_only(unique_nodes, source_stats, fetched, run_at)
    if args.skip_check:
        print("TCP check: skipped", flush=True)
        tcp_nodes = unique_nodes
    else:
        print(
            f"TCP check: started ({args.check_timeout:g}s timeout, {args.check_workers} workers)",
            flush=True,
        )
        tcp_nodes = check_nodes(unique_nodes, timeout=args.check_timeout, max_workers=args.check_workers)
    real_check_stats: dict[str, Any] = {"enabled": args.real_check}
    if args.real_check:
        real_check = check_nodes_via_singbox(
            tcp_nodes,
            sing_box=args.sing_box_bin,
            limit=args.real_check_limit,
            timeout=args.real_check_timeout,
            batch_size=args.real_check_batch_size,
        )
        working_nodes = real_check.nodes
        real_check_stats.update(
            {
                "selected": real_check.selected,
                "unsupported": real_check.unsupported,
                "invalid_batches": real_check.invalid_batches,
                "verified": len(working_nodes),
            }
        )
    else:
        working_nodes = tcp_nodes

    country_classified = 0
    cached_ips = 0
    queried_ips = 0
    ipinfo_token = os.environ.get("IPINFO_TOKEN")
    if ipinfo_token:
        try:
            country_classified, cached_ips, queried_ips = apply_ipinfo_countries(
                working_nodes, ipinfo_token, CACHE_FILE
            )
        except (OSError, ValueError) as error:
            print(f"WARN IPinfo country lookup: {error}", file=sys.stderr)
            country_classified = sum(node.country != "ZZ" for node in working_nodes)
    history = read_json(HISTORY_FILE, {"runs": 0, "nodes": {}})
    run_number = int(history.get("runs", 0)) + 1
    records = history.get("nodes", {})
    for node in working_nodes if args.real_check else []:
        recent = records.get(node_key(node), {}).get("recent_verified_runs", [])
        node.stability = (1 + sum(
            isinstance(run, int) and run > run_number - 5 for run in recent
        )) / 5

    working_nodes = sorted(
        working_nodes,
        key=lambda node: (
            node.latency_ms is None,
            node.latency_ms if node.latency_ms is not None else float("inf"),
            node.host,
            node.port,
        ),
    )
    speed_candidates: list[VlessNode] = []
    measured_nodes: list[VlessNode] = []
    if args.real_check:
        if len(working_nodes) <= SPEED_TEST_LIMIT:
            speed_candidates = working_nodes
        else:
            groups = group_by_country(working_nodes)
            candidates_by_country = {
                country: sorted(
                    nodes,
                    key=lambda node: node.latency_ms if node.latency_ms is not None else float("inf"),
                )[:SPEED_CANDIDATES_PER_COUNTRY]
                for country, nodes in groups.items()
            }
            for index in range(SPEED_CANDIDATES_PER_COUNTRY):
                for country in sorted(candidates_by_country):
                    candidates = candidates_by_country[country]
                    if index < len(candidates):
                        speed_candidates.append(candidates[index])
            speed_candidates = speed_candidates[:SPEED_TEST_LIMIT]
        measured_nodes = measure_speeds(speed_candidates, args.sing_box_bin)

    best_nodes: list[VlessNode] = []
    country_best: dict[str, list[VlessNode]] = {}
    for country, nodes in sorted(group_by_country(measured_nodes).items()):
        selected: list[VlessNode] = []
        seen_exits: set[str] = set()
        for node in rank(nodes, len(nodes)):
            if node.exit_ip in seen_exits:
                continue
            selected.append(node)
            seen_exits.add(node.exit_ip)
            if len(selected) == TOP_N:
                break
        country_best[country] = selected
        best_nodes.extend(country_best[country])

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_nodes(OUTPUT_DIR / "all-working.txt", working_nodes)
    if args.real_check:
        write_nodes(OUTPUT_DIR / "tcp-open.txt", tcp_nodes)
    write_labeled_nodes(OUTPUT_DIR / "best.txt", best_nodes)
    countries_dir = OUTPUT_DIR / "countries"
    countries_dir.mkdir(exist_ok=True)
    for path in countries_dir.glob("*.txt"):
        path.unlink()
    for country, nodes in country_best.items():
        write_labeled_nodes(countries_dir / f"{country}.txt", nodes)

    stats = {
        "generated_at": run_at,
        "country_mode": "exit_ip_ipinfo" if country_classified else "unknown_without_ip_geolocation",
        "security_filter": "tls,reality" if not args.include_insecure else "disabled",
        "sources": source_stats,
        "fetched_sources": sum(1 for result in fetched if not result.error),
        "failed_sources": sum(1 for result in fetched if result.error),
        "parsed_nodes": len(all_nodes),
        "unique_nodes": len(unique_nodes),
        "tcp_open_nodes": len(tcp_nodes),
        "working_nodes": len(working_nodes),
        "best_nodes": len(best_nodes),
        "real_check": real_check_stats,
        "speed_test": {"selected": len(speed_candidates), "measured": len(measured_nodes)},
        "country_classified_nodes": country_classified,
        "country_cached_ips": cached_ips,
        "country_queried_ips": queried_ips,
    }
    write_json(OUTPUT_DIR / "stats.json", stats)
    update_history(unique_nodes, working_nodes if args.real_check else [], run_at)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect and deduplicate public VLESS subscriptions")
    parser.add_argument(
        "--country-only",
        action="store_true",
        help="publish all VLESS whose server address is in the selected countries, without connectivity tests",
    )
    parser.add_argument(
        "--skip-check",
        action="store_true",
        help="skip DNS/TCP checks and publish all deduplicated nodes",
    )
    parser.add_argument(
        "--include-insecure",
        action="store_true",
        help="also keep security=none nodes",
    )
    parser.add_argument(
        "--check-timeout",
        type=float,
        default=2.0,
        help="DNS/TCP timeout per node in seconds (default: 2)",
    )
    parser.add_argument(
        "--check-workers",
        type=int,
        default=128,
        help="number of concurrent DNS/TCP checks (default: 128)",
    )
    parser.add_argument(
        "--real-check",
        action="store_true",
        help="verify VLESS traffic through sing-box after the TCP check",
    )
    parser.add_argument(
        "--sing-box-bin",
        default="sing-box",
        help="path to the sing-box binary (default: sing-box in PATH)",
    )
    parser.add_argument(
        "--real-check-limit",
        type=int,
        default=2000,
        help="maximum TCP-open nodes verified through sing-box per run (default: 2000)",
    )
    parser.add_argument(
        "--real-check-timeout",
        type=float,
        default=8.0,
        help="HTTP timeout through each VLESS node in seconds (default: 8)",
    )
    parser.add_argument(
        "--real-check-batch-size",
        type=int,
        default=64,
        help="number of VLESS nodes in one sing-box process (default: 64)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(build(parse_args()))
