from __future__ import annotations

from collections import defaultdict

from parser import VlessNode


def rank(nodes: list[VlessNode], top_n: int = 10) -> list[VlessNode]:
    return sorted(
        nodes,
        key=lambda node: (
            -(
                0.45 * min((node.speed_mbps or 0) / 100, 1)
                + 0.30 / (1 + (node.latency_ms or float("inf")) / 200)
                + 0.20 * node.stability
                + 0.05 * (1 if node.params.get("security") == "reality" else 0.8)
            ),
            -(node.speed_mbps or 0),
            node.host,
            node.port,
        ),
    )[:top_n]


def group_by_country(nodes: list[VlessNode]) -> dict[str, list[VlessNode]]:
    groups: dict[str, list[VlessNode]] = defaultdict(list)
    for node in nodes:
        groups[node.country].append(node)
    return dict(groups)
