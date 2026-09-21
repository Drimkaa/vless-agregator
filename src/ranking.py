from __future__ import annotations

from collections import defaultdict

from parser import VlessNode


def rank(nodes: list[VlessNode], top_n: int = 10) -> list[VlessNode]:
    return sorted(
        nodes,
        key=lambda node: (
            node.latency_ms is None,
            node.latency_ms if node.latency_ms is not None else float("inf"),
            node.host,
            node.port,
        ),
    )[:top_n]


def group_by_country(nodes: list[VlessNode]) -> dict[str, list[VlessNode]]:
    groups: dict[str, list[VlessNode]] = defaultdict(list)
    for node in nodes:
        groups[node.country].append(node)
    return dict(groups)
