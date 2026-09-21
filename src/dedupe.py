from __future__ import annotations

from parser import VlessNode


def canonical_key(node: VlessNode) -> tuple[str, ...]:
    params = node.params
    return (
        node.uuid,
        node.host,
        str(node.port),
        params.get("type", "tcp").lower(),
        params.get("security", "none").lower(),
        params.get("sni", "").lower(),
        params.get("host", "").lower(),
        params.get("path", ""),
        params.get("servicename", ""),
        params.get("pbk", params.get("publickey", "")),
        params.get("flow", "").lower(),
        params.get("mode", "").lower(),
        params.get("alpn", "").lower(),
        params.get("fp", "").lower(),
        params.get("sid", ""),
    )


def deduplicate(nodes: list[VlessNode]) -> list[VlessNode]:
    unique: dict[tuple[str, ...], VlessNode] = {}
    for node in nodes:
        key = canonical_key(node)
        existing = unique.get(key)
        if existing is None:
            unique[key] = node
            continue
        for source in node.sources:
            if source not in existing.sources:
                existing.sources.append(source)
    return list(unique.values())
