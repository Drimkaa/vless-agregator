from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dedupe import canonical_key, deduplicate
from fetch import fetch_all
from geo import apply_countries
from parser import VlessNode, is_secure, parse_source
from ranking import group_by_country, rank
from singbox import check_nodes_via_singbox
from tester import check_nodes


ROOT = Path(__file__).resolve().parents[1]
SOURCES_FILE = ROOT / "sources.json"
OUTPUT_DIR = ROOT / "output"
HISTORY_FILE = ROOT / "history.json"
TOP_N = 10


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


def update_history(nodes: list[VlessNode], run_at: str) -> None:
    history = read_json(HISTORY_FILE, {"runs": 0, "nodes": {}})
    history.setdefault("nodes", {})
    history["runs"] = int(history.get("runs", 0)) + 1
    history["last_run"] = run_at
    for node in nodes:
        key = node_key(node)
        record = history["nodes"].setdefault(key, {"runs": 0})
        record["runs"] = int(record.get("runs", 0)) + 1
        record["last_seen"] = run_at
    write_json(HISTORY_FILE, history)


def build(args: argparse.Namespace) -> int:
    run_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
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
        if not args.include_insecure:
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

    geoip_database_available = bool(args.geoip_db and Path(args.geoip_db).is_file())
    geoip_classified = 0
    if geoip_database_available:
        geoip_classified = apply_countries(working_nodes, Path(args.geoip_db))
    working_nodes = sorted(
        working_nodes,
        key=lambda node: (
            node.latency_ms is None,
            node.latency_ms if node.latency_ms is not None else float("inf"),
            node.host,
            node.port,
        ),
    )
    best_nodes = rank(working_nodes, TOP_N)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    write_nodes(OUTPUT_DIR / "all-working.txt", working_nodes)
    if args.real_check:
        write_nodes(OUTPUT_DIR / "tcp-open.txt", tcp_nodes)
    write_nodes(OUTPUT_DIR / "best.txt", best_nodes)
    for country, nodes in group_by_country(working_nodes).items():
        write_nodes(OUTPUT_DIR / "countries" / f"{country}.txt", rank(nodes, TOP_N))

    stats = {
        "generated_at": run_at,
        "country_mode": "exit_ip_geoip" if geoip_database_available else "unknown_until_geoip_database",
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
        "geoip_classified_nodes": geoip_classified,
    }
    write_json(OUTPUT_DIR / "stats.json", stats)
    update_history(unique_nodes, run_at)
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect and deduplicate public VLESS subscriptions")
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
    parser.add_argument(
        "--geoip-db",
        help="path to GeoLite2-Country.mmdb for exit-IP country lookup",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(build(parse_args()))
