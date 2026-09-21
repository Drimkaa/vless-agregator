from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from parser import VlessNode


def check_tcp(node: VlessNode, timeout: float = 2.0) -> bool:
    started = time.perf_counter()
    try:
        with socket.create_connection((node.host, node.port), timeout=timeout):
            pass
    except (OSError, ValueError):
        return False

    node.latency_ms = round((time.perf_counter() - started) * 1000, 1)
    return True


def check_nodes(
    nodes: list[VlessNode],
    timeout: float = 2.0,
    max_workers: int = 128,
    progress_every: int = 250,
) -> list[VlessNode]:
    working: list[VlessNode] = []
    completed = 0
    total = len(nodes)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_tcp, node, timeout): node for node in nodes}
        for future in as_completed(futures):
            node = futures[future]
            if future.result():
                working.append(node)
            completed += 1
            if progress_every and (completed % progress_every == 0 or completed == total):
                print(f"TCP check: {completed}/{total}, working={len(working)}", flush=True)
    return sorted(working, key=lambda node: (node.latency_ms or float("inf"), node.host, node.port))
